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
    /// The hyperparameters used for the fine-tuning job. See the [fine-tuning guide](/docs/guides/fine-tuning) for more details.
    /// </summary>
    [DataContract]
    public partial class FineTuningJobHyperparameters : IEquatable<FineTuningJobHyperparameters>
    { 
        /// <summary>
        /// The number of epochs to train the model for. An epoch refers to one full cycle through the training dataset. \&quot;auto\&quot; decides the optimal number of epochs based on the size of the dataset. If setting the number manually, we support any number between 1 and 50 epochs.
        /// </summary>
        /// <value>The number of epochs to train the model for. An epoch refers to one full cycle through the training dataset. \&quot;auto\&quot; decides the optimal number of epochs based on the size of the dataset. If setting the number manually, we support any number between 1 and 50 epochs.</value>
        [Required]

        [DataMember(Name="n_epochs")]
        public OneOfFineTuningJobHyperparametersNEpochs NEpochs { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class FineTuningJobHyperparameters {\n");
            sb.Append("  NEpochs: ").Append(NEpochs).Append("\n");
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
            return obj.GetType() == GetType() && Equals((FineTuningJobHyperparameters)obj);
        }

        /// <summary>
        /// Returns true if FineTuningJobHyperparameters instances are equal
        /// </summary>
        /// <param name="other">Instance of FineTuningJobHyperparameters to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(FineTuningJobHyperparameters other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    NEpochs == other.NEpochs ||
                    NEpochs != null &&
                    NEpochs.Equals(other.NEpochs)
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
                    if (NEpochs != null)
                    hashCode = hashCode * 59 + NEpochs.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(FineTuningJobHyperparameters left, FineTuningJobHyperparameters right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(FineTuningJobHyperparameters left, FineTuningJobHyperparameters right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
