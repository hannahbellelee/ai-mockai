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
    public partial class CreateThreadRequest : IEquatable<CreateThreadRequest>
    { 
        /// <summary>
        /// A list of [messages](/docs/api-reference/messages) to start the thread with.
        /// </summary>
        /// <value>A list of [messages](/docs/api-reference/messages) to start the thread with.</value>

        [DataMember(Name="messages")]
        public List<CreateMessageRequest> Messages { get; set; }

        /// <summary>
        /// Gets or Sets ToolResources
        /// </summary>

        [DataMember(Name="tool_resources")]
        public CreateThreadRequestToolResources ToolResources { get; set; }

        /// <summary>
        /// Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. 
        /// </summary>
        /// <value>Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. </value>

        [DataMember(Name="metadata")]
        public Object Metadata { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CreateThreadRequest {\n");
            sb.Append("  Messages: ").Append(Messages).Append("\n");
            sb.Append("  ToolResources: ").Append(ToolResources).Append("\n");
            sb.Append("  Metadata: ").Append(Metadata).Append("\n");
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
            return obj.GetType() == GetType() && Equals((CreateThreadRequest)obj);
        }

        /// <summary>
        /// Returns true if CreateThreadRequest instances are equal
        /// </summary>
        /// <param name="other">Instance of CreateThreadRequest to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CreateThreadRequest other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Messages == other.Messages ||
                    Messages != null &&
                    Messages.SequenceEqual(other.Messages)
                ) && 
                (
                    ToolResources == other.ToolResources ||
                    ToolResources != null &&
                    ToolResources.Equals(other.ToolResources)
                ) && 
                (
                    Metadata == other.Metadata ||
                    Metadata != null &&
                    Metadata.Equals(other.Metadata)
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
                    if (Messages != null)
                    hashCode = hashCode * 59 + Messages.GetHashCode();
                    if (ToolResources != null)
                    hashCode = hashCode * 59 + ToolResources.GetHashCode();
                    if (Metadata != null)
                    hashCode = hashCode * 59 + Metadata.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(CreateThreadRequest left, CreateThreadRequest right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CreateThreadRequest left, CreateThreadRequest right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
