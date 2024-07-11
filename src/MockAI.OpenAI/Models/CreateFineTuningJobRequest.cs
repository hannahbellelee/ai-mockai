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
    public partial class CreateFineTuningJobRequest : IEquatable<CreateFineTuningJobRequest>
    { 
        /// <summary>
        /// The name of the model to fine-tune. You can select one of the [supported models](/docs/guides/fine-tuning/what-models-can-be-fine-tuned). 
        /// </summary>
        /// <value>The name of the model to fine-tune. You can select one of the [supported models](/docs/guides/fine-tuning/what-models-can-be-fine-tuned). </value>
        [Required]

        [DataMember(Name="model")]
        public AnyOfCreateFineTuningJobRequestModel Model { get; set; }

        /// <summary>
        /// The ID of an uploaded file that contains training data.  See [upload file](/docs/api-reference/files/create) for how to upload a file.  Your dataset must be formatted as a JSONL file. Additionally, you must upload your file with the purpose &#x60;fine-tune&#x60;.  The contents of the file should differ depending on if the model uses the [chat](/docs/api-reference/fine-tuning/chat-input) or [completions](/docs/api-reference/fine-tuning/completions-input) format.  See the [fine-tuning guide](/docs/guides/fine-tuning) for more details. 
        /// </summary>
        /// <value>The ID of an uploaded file that contains training data.  See [upload file](/docs/api-reference/files/create) for how to upload a file.  Your dataset must be formatted as a JSONL file. Additionally, you must upload your file with the purpose &#x60;fine-tune&#x60;.  The contents of the file should differ depending on if the model uses the [chat](/docs/api-reference/fine-tuning/chat-input) or [completions](/docs/api-reference/fine-tuning/completions-input) format.  See the [fine-tuning guide](/docs/guides/fine-tuning) for more details. </value>
        [Required]

        [DataMember(Name="training_file")]
        public string TrainingFile { get; set; }

        /// <summary>
        /// Gets or Sets Hyperparameters
        /// </summary>

        [DataMember(Name="hyperparameters")]
        public CreateFineTuningJobRequestHyperparameters Hyperparameters { get; set; }

        /// <summary>
        /// A string of up to 18 characters that will be added to your fine-tuned model name.  For example, a &#x60;suffix&#x60; of \&quot;custom-model-name\&quot; would produce a model name like &#x60;ft:gpt-3.5-turbo:openai:custom-model-name:7p4lURel&#x60;. 
        /// </summary>
        /// <value>A string of up to 18 characters that will be added to your fine-tuned model name.  For example, a &#x60;suffix&#x60; of \&quot;custom-model-name\&quot; would produce a model name like &#x60;ft:gpt-3.5-turbo:openai:custom-model-name:7p4lURel&#x60;. </value>

        [StringLength(40, MinimumLength=1)]
        [DataMember(Name="suffix")]
        public string Suffix { get; set; }

        /// <summary>
        /// The ID of an uploaded file that contains validation data.  If you provide this file, the data is used to generate validation metrics periodically during fine-tuning. These metrics can be viewed in the fine-tuning results file. The same data should not be present in both train and validation files.  Your dataset must be formatted as a JSONL file. You must upload your file with the purpose &#x60;fine-tune&#x60;.  See the [fine-tuning guide](/docs/guides/fine-tuning) for more details. 
        /// </summary>
        /// <value>The ID of an uploaded file that contains validation data.  If you provide this file, the data is used to generate validation metrics periodically during fine-tuning. These metrics can be viewed in the fine-tuning results file. The same data should not be present in both train and validation files.  Your dataset must be formatted as a JSONL file. You must upload your file with the purpose &#x60;fine-tune&#x60;.  See the [fine-tuning guide](/docs/guides/fine-tuning) for more details. </value>

        [DataMember(Name="validation_file")]
        public string ValidationFile { get; set; }

        /// <summary>
        /// A list of integrations to enable for your fine-tuning job.
        /// </summary>
        /// <value>A list of integrations to enable for your fine-tuning job.</value>

        [DataMember(Name="integrations")]
        public List<CreateFineTuningJobRequestIntegrations> Integrations { get; set; }

        /// <summary>
        /// The seed controls the reproducibility of the job. Passing in the same seed and job parameters should produce the same results, but may differ in rare cases. If a seed is not specified, one will be generated for you. 
        /// </summary>
        /// <value>The seed controls the reproducibility of the job. Passing in the same seed and job parameters should produce the same results, but may differ in rare cases. If a seed is not specified, one will be generated for you. </value>

        [Range(0, 2147483647)]
        [DataMember(Name="seed")]
        public int? Seed { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CreateFineTuningJobRequest {\n");
            sb.Append("  Model: ").Append(Model).Append("\n");
            sb.Append("  TrainingFile: ").Append(TrainingFile).Append("\n");
            sb.Append("  Hyperparameters: ").Append(Hyperparameters).Append("\n");
            sb.Append("  Suffix: ").Append(Suffix).Append("\n");
            sb.Append("  ValidationFile: ").Append(ValidationFile).Append("\n");
            sb.Append("  Integrations: ").Append(Integrations).Append("\n");
            sb.Append("  Seed: ").Append(Seed).Append("\n");
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
            return obj.GetType() == GetType() && Equals((CreateFineTuningJobRequest)obj);
        }

        /// <summary>
        /// Returns true if CreateFineTuningJobRequest instances are equal
        /// </summary>
        /// <param name="other">Instance of CreateFineTuningJobRequest to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CreateFineTuningJobRequest other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Model == other.Model ||
                    Model != null &&
                    Model.Equals(other.Model)
                ) && 
                (
                    TrainingFile == other.TrainingFile ||
                    TrainingFile != null &&
                    TrainingFile.Equals(other.TrainingFile)
                ) && 
                (
                    Hyperparameters == other.Hyperparameters ||
                    Hyperparameters != null &&
                    Hyperparameters.Equals(other.Hyperparameters)
                ) && 
                (
                    Suffix == other.Suffix ||
                    Suffix != null &&
                    Suffix.Equals(other.Suffix)
                ) && 
                (
                    ValidationFile == other.ValidationFile ||
                    ValidationFile != null &&
                    ValidationFile.Equals(other.ValidationFile)
                ) && 
                (
                    Integrations == other.Integrations ||
                    Integrations != null &&
                    Integrations.SequenceEqual(other.Integrations)
                ) && 
                (
                    Seed == other.Seed ||
                    Seed != null &&
                    Seed.Equals(other.Seed)
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
                    if (Model != null)
                    hashCode = hashCode * 59 + Model.GetHashCode();
                    if (TrainingFile != null)
                    hashCode = hashCode * 59 + TrainingFile.GetHashCode();
                    if (Hyperparameters != null)
                    hashCode = hashCode * 59 + Hyperparameters.GetHashCode();
                    if (Suffix != null)
                    hashCode = hashCode * 59 + Suffix.GetHashCode();
                    if (ValidationFile != null)
                    hashCode = hashCode * 59 + ValidationFile.GetHashCode();
                    if (Integrations != null)
                    hashCode = hashCode * 59 + Integrations.GetHashCode();
                    if (Seed != null)
                    hashCode = hashCode * 59 + Seed.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(CreateFineTuningJobRequest left, CreateFineTuningJobRequest right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CreateFineTuningJobRequest left, CreateFineTuningJobRequest right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
