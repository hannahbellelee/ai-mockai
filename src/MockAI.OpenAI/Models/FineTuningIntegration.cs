/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace IO.Swagger.Models
{
    /// <summary>
    /// 
    /// </summary>
    [DataContract]
    public partial class FineTuningIntegration : IEquatable<FineTuningIntegration>, OneOfFineTuningJobIntegrationsItems 
    { 
        /// <summary>
        /// The type of the integration being enabled for the fine-tuning job
        /// </summary>
        /// <value>The type of the integration being enabled for the fine-tuning job</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum WandbEnum for wandb
            /// </summary>
            [EnumMember(Value = "wandb")]
            WandbEnum = 0        }

        /// <summary>
        /// The type of the integration being enabled for the fine-tuning job
        /// </summary>
        /// <value>The type of the integration being enabled for the fine-tuning job</value>
        [Required]

        [DataMember(Name="type")]
        public TypeEnum? Type { get; set; }

        /// <summary>
        /// Gets or Sets Wandb
        /// </summary>
        [Required]

        [DataMember(Name="wandb")]
        public CreateFineTuningJobRequestWandb Wandb { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class FineTuningIntegration {\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  Wandb: ").Append(Wandb).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((FineTuningIntegration)obj);
        }

        /// <summary>
        /// Returns true if FineTuningIntegration instances are equal
        /// </summary>
        /// <param name="other">Instance of FineTuningIntegration to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(FineTuningIntegration other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Type == other.Type ||
                    Type != null &&
                    Type.Equals(other.Type)
                ) && 
                (
                    Wandb == other.Wandb ||
                    Wandb != null &&
                    Wandb.Equals(other.Wandb)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    if (Type != null)
                    hashCode = hashCode * 59 + Type.GetHashCode();
                    if (Wandb != null)
                    hashCode = hashCode * 59 + Wandb.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(FineTuningIntegration left, FineTuningIntegration right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(FineTuningIntegration left, FineTuningIntegration right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
